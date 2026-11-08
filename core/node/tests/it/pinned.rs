#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Past bugs the sim once found, by seed; sim seeds do not last, so each has its scenario here by
//! hand. Each test's comment names the bug and the sim scenario.

use crate::net;
use net::*;
use osis_base::{Ak, BlobId, CommitId, LabelId, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::flows::Demotion;
use osis_node::sync::{EntryKind, Event, SyncConfig};
use osis_schema::{RawKey, Codec};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

static KEEP: osis_schema::StaticSchema = osis_schema::StaticSchema::new(
    "pinned.osis",
    r#"
revision 1;
purgeable_by(writer) keep_history(1d) aspect p:one.0: string;
purgeable_by(writer) keep_history(1d) aspect p:two.0: string;
"#,
);
const ONE: osis_schema::Aspect<Value> = osis_schema::Aspect::new("p:one.0", &KEEP);
const TWO: osis_schema::Aspect<Value> = osis_schema::Aspect::new("p:two.0", &KEEP);

/// Blob IDs node `n` knows under `l` holding commit `c`.
fn blobs_of(net: &mut Net, n: usize, l: &LabelId, c: &CommitId) -> BTreeSet<BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c)).map(|(id, _)| id).collect()
}

/// Blobs node `n` knows under `l` and never opened.
fn unopened(net: &mut Net, n: usize, l: &LabelId) -> BTreeSet<BlobId> {
    net.sync(n).entries(l).into_iter().filter(|(_, k)| *k == EntryKind::Unknown).map(|(id, _)| id).collect()
}

/// Deletions in host `host`'s log of `l`.
fn deletions(net: &Net, host: usize, l: &LabelId) -> usize {
    use osis_proto::{LabelStore, LogRecord};
    let recs = net.hosts[host].hub.store().log_after(l, 0, 1 << 20).unwrap().unwrap_or_default();
    recs.iter().filter(|(_, r)| matches!(r, LogRecord::Deleted(_))).count()
}

// spec/sync.md §6, spec/commits.md §4 (sim two_nodes_host): an entry announced, its fetch lost
// with the connection: the cursor is past it, so no host tells of it again. It stayed unopened
// for good, which also froze what its holder judged must-hold, and the other node waited for
// that holder's commits. Now a pass fetches it again.
#[test]
fn entry_whose_fetch_was_lost_is_fetched_again_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let cfg = SyncConfig { hosts: vec![net.address(host)], inline_limit: 0, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    assert!(unopened(&mut net, a, &l).is_empty());
    let c = net.write(b, t, "from b");
    net.feed(b, Event::Local);
    // until `a` was told of the entry; its fetch is under way
    let mut rounds = 0;
    while unopened(&mut net, a, &l).is_empty() {
        net.round();
        rounds += 1;
        assert!(rounds < 100, "never announced");
    }
    assert_eq!(net.read(a, t), Some(s("x")));
    net.drop_link(a, host);
    net.settle(200_000);
    assert_eq!(unopened(&mut net, a, &l).len(), 1, "the fetch went with the connection");
    assert!(net.engine(a).header(&c).is_none());
    // past the redial pause; the host has nothing new to tell it
    net.advance(6_000);
    net.advance(61_000);
    assert_eq!(net.read(a, t), Some(s("from b")), "fetched again");
    assert!(unopened(&mut net, a, &l).is_empty());
    // and what `a` writes after goes up and reaches the other node
    net.write(a, t, "from a");
    net.run();
    assert_eq!(net.read(b, t), Some(s("from a")));
}

// spec/sync.md §6, §7 (sim stranded_reseal): a relayer's upload of another node's commit is lost;
// the author's own encryption arrives meanwhile. The relayer's retry must see the body present:
// it re-uploaded its own, and where that had the lower blob ID the tiebreak deleted the author's
// after quiescence. Whether the relayer's ID is the lower is the seeds' roll, so seeds until it is.
#[test]
fn relayer_retry_leaves_the_authors_entry_spec_sync_6() {
    let mut lower = 0;
    for seed in 0..12 {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(10 + 2 * seed, &[host]);
        let b = net.node(11 + 2 * seed, &[host]);
        let g = net.group(a, &[(b, Role::Write)], &[host]);
        let t = net.item(a, g, g, "x");
        net.run();
        let l = net.label(a);
        // the author away; the relayer holds its commit, past the relay wait, its upload lost
        net.set_online(a, false);
        let c = net.write(a, t, "y");
        let pk = net.engine(a).package(&c).unwrap().unwrap();
        net.engine(b).ingest(&pk.bytes, pk.blobs).unwrap();
        net.lose_uploads.insert(b);
        net.advance(61_000);
        let mine = blobs_of(&mut net, b, &l, &c);
        assert_eq!(mine.len(), 1, "seed {seed}: the relayer's encryption");
        let mine = *mine.first().unwrap();
        assert!(!net.host_ids(host, &l).contains(&mine), "seed {seed}: lost");
        // the author back: its entry reaches the relayer before the retry goes through
        net.set_online(a, true);
        net.advance(6_000);
        net.run();
        let theirs = *blobs_of(&mut net, a, &l, &c).iter().find(|x| **x != mine).unwrap();
        assert!(net.host_ids(host, &l).contains(&theirs), "seed {seed}: the author's is up");
        assert!(blobs_of(&mut net, b, &l, &c).contains(&theirs), "seed {seed}: the relayer heard");
        lower += usize::from(mine < theirs);
        net.lose_uploads.clear();
        for _ in 0..3 {
            net.advance(61_000);
        }
        let ids = net.host_ids(host, &l);
        assert!(!ids.contains(&mine), "seed {seed}: the relayer uploaded its own though the body was there");
        assert!(ids.contains(&theirs), "seed {seed}: the author's entry deleted");
        assert_eq!(net.read(b, t), Some(s("y")));
        if lower > 0 {
            return;
        }
    }
    panic!("no seed gave the relayer the lower ID");
}

// spec/sync.md §5 (re-registration uploads the role commits a host lacks), §7 (sim stranded_reseal):
// as above for a role commit, where nothing else stops the upload: the relayer of an admin's
// rotation lost its upload, the author's arrived, and the relayer's next step uploaded its own
// encryption as lacking, so the tiebreak could delete the author's.
#[test]
fn step_uploads_no_second_encryption_of_a_present_role_commit_spec_sync_5() {
    let mut lower = 0;
    for seed in 0..12 {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(40 + 3 * seed, &[host]);
        let b = net.node(41 + 3 * seed, &[host]);
        let c = net.node(42 + 3 * seed, &[host]);
        let d = net.node(90 + seed, &[host]);
        let g = net.group(a, &[(b, Role::Admin), (c, Role::Write), (d, Role::Write)], &[host]);
        net.run();
        net.advance(31_000);
        let l = net.label(a);
        // the author away with its rotation; the relayer's uploads are lost
        net.set_online(a, false);
        let holder = net.tid(c);
        let seen: BTreeSet<CommitId> = net.engine(a).aspect_commits(&g, "secrets.0").into_iter().map(|x| x.0).collect();
        net.engine(a).demote(&g, &Demotion { holder, new: None, retain: None }).unwrap();
        let rotation = net.engine(a).aspect_commits(&g, "secrets.0").into_iter().map(|x| x.0).find(|x| !seen.contains(x)).unwrap();
        let pk = net.engine(a).package(&rotation).unwrap().unwrap();
        net.engine(b).ingest(&pk.bytes, pk.blobs).unwrap();
        net.lose_uploads.insert(b);
        net.advance(61_000);
        let mine = blobs_of(&mut net, b, &l, &rotation);
        assert!(!mine.is_empty(), "seed {seed}: the relayer's encryption");
        let at = net.host_ids(host, &l);
        assert!(mine.iter().all(|x| !at.contains(x)), "seed {seed}: lost");
        // the author's reaches the host and the relayer
        net.set_online(a, true);
        net.advance(6_000);
        net.run();
        let theirs: BTreeSet<BlobId> = net.host_ids(host, &l).into_iter().filter(|x| blobs_of(&mut net, b, &l, &rotation).contains(x)).collect();
        assert!(!theirs.is_empty(), "seed {seed}: the author's is up, the relayer heard");
        lower += usize::from(mine.iter().min() < theirs.iter().min());
        net.lose_uploads.clear();
        // the relayer's own next rotation: a step, with the role commits the host lacks
        let holder = net.tid(d);
        let done = net.engine(b).demote(&g, &Demotion { holder, new: None, retain: None }).unwrap();
        let acts = net.sync(b).carry_out(done).unwrap();
        net.actions(b, acts);
        net.advance(61_000);
        net.advance(61_000);
        let at = net.host_ids(host, &l);
        assert!(mine.iter().all(|x| !at.contains(x)), "seed {seed}: the relayer uploaded its own though the body was there");
        assert!(theirs.iter().all(|x| at.contains(x)), "seed {seed}: the author's entry deleted");
        if lower > 0 {
            return;
        }
    }
    panic!("no seed gave the relayer the lower ID");
}

/// `crossed_snapshots_drop_alike_*`: the host's deletions of `l` from before the bound on, and the
/// blobs of the shared commit either writer knew.
fn crossed_snapshots() -> (usize, usize) {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    let both = |net: &mut Net, n: usize, v: &str| {
        let mut m = Mutation::new();
        m.set(t, &ONE, &s(v)).unwrap();
        m.set(t, &TWO, &s(v)).unwrap();
        let c = net.engine(n).commit(m).unwrap().unwrap();
        net.advance(1_000);
        c
    };
    let shared = both(&mut net, a, "v1");
    both(&mut net, a, "v2");
    let l = net.label(a);
    // each compacts one aspect, before the bound: nothing drops yet
    for (n, k) in [(a, Ak::new(ONE.ak()).unwrap()), (b, Ak::new(TWO.ak()).unwrap())] {
        let acts = net.sync(n).compact(&t, &k).unwrap();
        net.actions(n, acts);
        net.run();
    }
    let before = deletions(&net, host, &l);
    let mut seen = BTreeSet::new();
    net.advance(86_400_000 - 3_600_000);
    for _ in 0..30 {
        net.advance(5 * 60_000);
        for n in [a, b] {
            seen.extend(blobs_of(&mut net, n, &l, &shared));
        }
    }
    for n in [a, b] {
        for k in [Ak::new(ONE.ak()).unwrap(), Ak::new(TWO.ak()).unwrap()] {
            assert!(!net.engine(n).body_not_dropped(&shared, &t, &k), "node {n}: {k:?} of the covered commit kept");
        }
    }
    (deletions(&net, host, &l) - before, seen.len())
}

// spec/sync.md §6, §7 (sim compaction): two writers compact one aspect each of a commit on both,
// past the bound. Each dropped only what the other's snapshot covered, not its own, so each held
// a different part of the commit and deleted the other's: a delete and re-place storm. Now
// both drop the whole commit, its one blob deleted once.
#[test]
fn crossed_snapshots_drop_alike_spec_sync_7() {
    assert_eq!(crossed_snapshots(), (1, 1), "deletions, blobs of the commit");
}

/// Node `n` records `g`'s label `l`'s head step in `label.0` again: a role commit, no rotation.
fn record_step_again(net: &mut Net, n: usize, g: Tid, l: LabelId) {
    let gl = net.engine(n).group_labels(&g).unwrap().into_iter().find(|x| x.id == l).unwrap();
    let (id, (step, _)) = gl.steps.iter().next_back().unwrap();
    let path = vec![PathSeg::Key(l.to_value()), PathSeg::Field(1), PathSeg::Key(id.0.to_value())];
    let mut m = Mutation::new();
    m.op(g, &ct::LABEL, PathOp { path, op: Op::Set(osis_label::step_record(step, None).to_value()) }).unwrap();
    net.engine(n).commit(m).unwrap().unwrap();
}

// spec/sync.md §5 (one step per rotation), spec/permissions.md §3, §4 (sim stranded_reseal): another
// admin's `label.0` write is no rotation: this admin's next rotation gets its step at once. It
// was held back the settle wait, so the next rotation in that wait shared the step and a stale
// node claimed through.
#[test]
fn label_record_delays_no_step_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Admin), (c, Role::Write)], &[host]);
    net.run();
    let l = net.label(a);
    let steps = |net: &mut Net, n: usize| net.engine(n).group_labels(&g).unwrap().into_iter().find(|x| x.id == l).unwrap().steps.len();
    let path = net.host_path(host, &l).len();
    assert_eq!(steps(&mut net, b), path);
    // the setup's own rotations out of the settle wait
    net.advance(31_000);
    record_step_again(&mut net, a, g, l);
    net.run();
    let holder = net.tid(c);
    let done = net.engine(b).demote(&g, &Demotion { holder, new: None, retain: None }).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    // no time passes
    net.run();
    assert_eq!(net.host_path(host, &l).len(), path + 1, "the rotation's step registered at once");
    assert_eq!(steps(&mut net, b), path + 1);
    // and the other admin, past its wait, adds none
    net.advance(31_000);
    assert_eq!(net.host_path(host, &l).len(), path + 1);
    assert_eq!(steps(&mut net, a), path + 1);
}
